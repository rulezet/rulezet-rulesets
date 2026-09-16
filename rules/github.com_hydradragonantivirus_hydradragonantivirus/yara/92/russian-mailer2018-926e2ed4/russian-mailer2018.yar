rule RUSSIAN_MAILER2018 {
  meta:
    description = "Tryag-File-Manager-jpeg-master - file RUSSIAN-MAILER2018.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-07-14"
    hash1       = "fc90f92c91ca7b149c9e268053e23e816e49e4613dcf9f09c318882cde8c5ecb"

  strings:
    $s1 = "$message = stripslashes($message);" fullword ascii
    $s2 = "$driv3r = $email[$i];" fullword ascii
    
  condition:
    all of them
}