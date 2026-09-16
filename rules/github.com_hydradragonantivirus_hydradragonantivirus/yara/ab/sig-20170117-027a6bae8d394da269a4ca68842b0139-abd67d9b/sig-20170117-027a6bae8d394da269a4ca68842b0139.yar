rule sig_20170117_027a6bae8d394da269a4ca68842b0139 {
  meta:
    description = "datamaliciousorder - file 20170117_027a6bae8d394da269a4ca68842b0139.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "61ba0b7af091d0c4f70cd0d2ed2567dcef810a8f9a27e9337136c27d6343da65"

  strings:
    $s1 = "var bbehhikdycgo5 = new Function(opqyhucufodwyttufkytdyrninohrotumxipeharam[0] + ragqehguvejopwyjnozuhoxrojuqaswyfmikgitzatgawy[" ascii
    $s2 = "var bbehhikdycgo5 = new Function(opqyhucufodwyttufkytdyrninohrotumxipeharam[0] + ragqehguvejopwyjnozuhoxrojuqaswyfmikgitzatgawy[" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}