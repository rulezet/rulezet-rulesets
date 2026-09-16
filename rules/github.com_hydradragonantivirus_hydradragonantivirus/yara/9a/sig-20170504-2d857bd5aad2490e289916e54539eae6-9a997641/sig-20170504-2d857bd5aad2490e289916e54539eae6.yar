rule sig_20170504_2d857bd5aad2490e289916e54539eae6 {
  meta:
    description = "datamaliciousorder - file 20170504_2d857bd5aad2490e289916e54539eae6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e07e276dd7d418d1ac890fc27b4d346c43891271dca00975365f35acead27636"

  strings:
    $s1 = "this[\"e\\u0076\\x61\\u006c\"](\"\\x6e\\u0065\\x77 \\x41\\u0063\\u0074\\x69\\u0076\\x65X\\u004fb\\152\\x65\\u0063t\\u0028\\x22" ascii
    $s2 = "this[\"e\\u0076\\x61\\u006c\"](\"\\x6e\\u0065\\x77 \\x41\\u0063\\u0074\\x69\\u0076\\x65X\\u004fb\\152\\x65\\u0063t\\u0028\\x22" ascii

  condition:
    uint16(0) == 0x6874 and
    all of them
}