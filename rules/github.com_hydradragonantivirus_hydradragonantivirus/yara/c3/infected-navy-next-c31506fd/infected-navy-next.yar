rule infected_Navy_next {
  meta:
    description = "Navy - file next.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2020-07-23"
    hash1       = "f894037ff238b4e45e6961a191dc52ec6b09a471c031a08de7381acb0af7c001"

  strings:
    $x1  = "echo gzuncompress(base64_decode(\"eNokXdey6jqQffb9CjGEApMsCUsyoWDIOWcKKNIm5xy/fVpnHm44Z3vbCt2r15Jarf9KO5Q4nfYnVJ2dr9sZKs4el/+myy" ascii
    $x2  = "} elseif ((!empty($_SERVER['HTTP_CLIENT_IP'])) && (($_SERVER['HTTP_CLIENT_IP'])<>'127.0.0.1') && (($_SERVER['HTTP_CLIENT_IP'])<>" ascii
    $s3  = "$domain = 'UAJxURKDg7HljWK.MDQ'; $domains = 'J5snktaiZ'; $sourceid = '';  $flowdomain = 'f303050'; $codenamemode = 'API'; if (!f" ascii
    $s4  = "<?php if($_GET['mod']){if($_GET['mod']=='0XX' OR $_GET['mod']=='00X'){$g_sch=file_get_contents('http://www.google.com/safebrowsi" ascii
    $s5  = "<?php if($_GET['mod']){if($_GET['mod']=='0XX' OR $_GET['mod']=='00X'){$g_sch=file_get_contents('http://www.google.com/safebrowsi" ascii
    $s8  = "header(\"Content-Disposition: attachment; filename=\\\"2345234523.vbs\\\"\");" fullword ascii
    $s9  = "header(\"Content-Description: File Transfer\");" fullword ascii
    $s10 = "$g_sch = str_replace('\"listed\"', '', $g_sch, $g_out);if($g_out){header('HTTP/1.1 202');exit;}}if($_GET['mod']=='X0X' OR $_GET[" ascii
    $s11 = "od']=='00X'){$sh = gethostbyname($_SERVER['HTTP_HOST'].'.dbl.spamhaus.org');" fullword ascii
    $s12 = "$_SERVER['HTTP_ACCEPT_LANGUAGE'],0,2); $ch = curl_init(); curl_setopt($ch, CURLOPT_URL, 'http://104.193.252.21/apipost.php'); cu" ascii
    $s13 = "ARDED_FOR'])) && (($_SERVER['HTTP_X_FORWARDED_FOR'])<>'127.0.0.1') && (($_SERVER['HTTP_X_FORWARDED_FOR'])<>($_SERVER['SERVER_ADD" ascii
    $s14 = "header(\"Content-Transfer-Encoding: binary\");" fullword ascii
    $s15 = "2345234523" ascii  
    $s16 = "+RLm5yEkzohRclHCBCz+i90VF2kKrP30U5MdkQ4ipP0Gj0NTwn8tEmp0IYlNGPYJUs6li/ob5p7c4vGKYpjWI0g3alnGrfP4wlCxmA1OlKSLtmd5vdSwGttoB08d4z44" ascii
    $s17 = "0QoLGBPYbOEUy5ttjCV7fUB2HC6fZ7NhtkFPnACNI0/qqxHBhU3yQvprdKF36u27dF0kvFft8De3wgtI/KfvNElOgEoTUIFh6Dod81QwjEGJcbvQMm8vshxhqyUEG0/2" ascii
    $s18 = "USER_AGENT'])) { $_SERVER['HTTP_USER_AGENT'] = getenv('HTTP_USER_AGENT'); } return $_SERVER['HTTP_USER_AGENT']; }} $ua=getRealua" ascii
    $s19 = "GUJ39I0dlQ75251XC3G9lYhK+cfcdFawVfkmCj3DssbOqAptZNawlFH94zQGe7FuHIflTo0ivDmWDD3v0D+tHJi6g3oV4F4vCbR2foqHeXG6xvyp9dfTpQYdSq4GJXsW" ascii
    $s20 = "UPrwJt+aDDQ9htsePmFGiN4Doj9RQr0+0wrvofnbAgax/G9o7narRtZ5MGFrAf8DY78lxWnwdM9J89pErF67ZRiUKWu0f9LFTPdinhKFbjdze2iDNWaAemWBq3Z84XYV" ascii

  condition:
    uint16(0) == 0x3f3c and filesize < 500KB and
    1 of ($x*) and 4 of them
}