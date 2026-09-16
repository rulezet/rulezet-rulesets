rule wp_newsletter_v1 {
  meta:
    description = "shells - file wp-newsletter-v1.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-10-28"
    hash1       = "eec9fc9c2a24434541e7b3b26f5401a81ffbc12ecbbe3c0e728fecee71146259"

  strings:
    $x1  = "curl_setopt($ch, CURLOPT_USERAGENT, \"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 6.1; .NET CLR 1.1.4322)\");" fullword ascii
    $x2  = "if ($urlShell === false && preg_match('/' . preg_quote(\"[shell_rewrite_url]\", \"/\") . '/i', $Command['content'])) {" fullword ascii
    $s3  = "$privKeyStr = !empty($this->DKIM_private_string) ? $this->DKIM_private_string : @file_get_contents($this->DKIM_private);" fullword ascii
    $s4  = "$mime[] = sprintf('Content-Type: %s; name=\"%s\"%s', $type, $this->encodeHeader($this->secureHeader($name)), $this->LE);" fullword ascii
    $s5  = "if (version_compare(PHP_VERSION, '5.3.0') >= 0 and in_array('sha256WithRSAEncryption', openssl_get_md_methods(true))) {" fullword ascii
    $s6  = "if (!$this->sendCommand('User & Password', base64_encode(\"\\0\" . $username . \"\\0\" . $password), 235)) {" fullword ascii
    $s7  = "$checkread = @GetPageContent(' . $Function2 . '() . $image_name . \"?\" . http_build_query($parameters) );" fullword ascii
    $s8  = "$mime[] = sprintf('Content-Type: %s; name=\"%s\"%s', $type, $this->encodeHeader($this->secureHeader($name)), $" fullword ascii
    $s9  = "$mime[] = sprintf('Content-Disposition: %s; filename=%s%s', $disposition, $encoded_name, $this->LE . $this->LE);" fullword ascii
    $s10 = "$SERVER_INFOS['REAL_IP_GET']     = GetPageContent(\"http://myip.dnsomatic.com/\");" fullword ascii
    $s11 = "return $this->language[$key] . ' https://github.com/SilthxMailer/SilthxMailer/wiki/Troubleshooting';" fullword ascii
    $s12 = "$this->smtp_conn = @stream_socket_client($host . \":\" . $port, $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, " fullword ascii
    $s13 = "$mime[] = sprintf('Content-Disposition: %s; filename=%s%s', $disposition, $encoded_name, $this->LE ." fullword ascii
    $s14 = "$mail->addStringAttachment(GetPageContent($Command['file']), $Command['filename'] . \".\" . $FileExtension);" fullword ascii
    $s15 = "fwrite($SocksSocket, pack(\"C4Nn\", 0x05, 0x01, 0x00, 0x01, ip2long(gethostbyname($host)), $port));" fullword ascii
    $s16 = "return html_entity_decode(trim(strip_tags(preg_replace('/<(head|title|style|script)[^>]*>.*?<\\/\\\\1>/si', '', $html))), E" fullword ascii
    $s17 = "$noerror         = $this->sendCommand($hello, $hello . ' ' . $host, 250);" fullword ascii
    $s18 = "$this->edebug(\"The SOCKS server failed to connect to the specificed host and port. ( \" . $host . \":\" . $port . \"" fullword ascii
    $s19 = "return (strlen($address) >= 3 and strpos($address, '@') >= 1 and strpos($address, '@') != strlen($address) - 1);" fullword ascii
    $s20 = "$mime[] = sprintf('Content-Disposition: %s; filename=\"%s\"%s', $disposition, $encoded_name, $this->LE . $this->LE);" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 400KB and
      (1 of ($x*) and 4 of them)
    ) or (all of them)
}