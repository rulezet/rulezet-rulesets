rule mal_sugarghost_ee5982_log_strings_xor {
  meta:
    author      = "stvemillertime"
    date        = "2024-01-09"
    description = "This looks for odd strings from a sample cited in https://blog.talosintelligence.com/new-sugargh0st-rat/"
    sample      = "ee5982a71268c84a5c062095ce135780b8c2ffb1f266c2799173fb0f7bfdd33e"
    
  strings:
            $str1 = "%4.2f GB" xor(0x01-0xff)
    $str2 = "%4.2f MB" xor(0x01-0xff)
    $str3 = "%4.2f KB" xor(0x01-0xff)
        $str4 = "%d Bytes" xor(0x01-0xff)

  condition:
    uint16be(0) == 0x4d5a and
    filesize < 10MB and
    2 of them  }