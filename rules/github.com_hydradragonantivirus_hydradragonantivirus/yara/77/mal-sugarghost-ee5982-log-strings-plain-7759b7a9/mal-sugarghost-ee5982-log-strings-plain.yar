rule mal_sugarghost_ee5982_log_strings_plain {
  meta:
    author      = "stvemillertime"
    date        = "2024-01-09"
    description = "This looks for odd strings from a sample cited in https://blog.talosintelligence.com/new-sugargh0st-rat/"
    sample      = "ee5982a71268c84a5c062095ce135780b8c2ffb1f266c2799173fb0f7bfdd33e"
    
  strings:
            $str1 = "%4.2f GB" ascii wide
    $str2 = "%4.2f MB" ascii wide
    $str3 = "%4.2f KB" ascii wide
        $str4 = "%d Bytes" ascii wide

  condition:
    uint16be(0) == 0x4d5a and
    filesize < 10MB and
    2 of them  }