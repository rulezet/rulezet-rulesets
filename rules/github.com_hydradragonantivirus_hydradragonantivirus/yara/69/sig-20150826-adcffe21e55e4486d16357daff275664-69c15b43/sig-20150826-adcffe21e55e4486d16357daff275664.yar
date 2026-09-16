rule sig_20150826_adcffe21e55e4486d16357daff275664 {
  meta:
    description = "datamaliciousorder - file 20150826_adcffe21e55e4486d16357daff275664.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b8239c4707d624089e598df827dc6635bbcd5326a94628a0ecc6e6c33606103"

  strings:
    $s1 = "var key = 'gzYmY0cYk3t';var b = '\\x17=2.\\x0bq\\x07!\\x1fP7\\x10;aMd\\x10A7Y\\x06V\\x5cwS\\x0b,^\\x00-\\x02\\x5c\\x1aG\\x0a\\x1" ascii
    $s2 = "), ZWsvmVyjHUYxbOx7++, ZWsvmVyjHUYxbOx7 == key.length && (ZWsvmVyjHUYxbOx7 = 0);print(ZWsvmVyjHUYxbOx5);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}