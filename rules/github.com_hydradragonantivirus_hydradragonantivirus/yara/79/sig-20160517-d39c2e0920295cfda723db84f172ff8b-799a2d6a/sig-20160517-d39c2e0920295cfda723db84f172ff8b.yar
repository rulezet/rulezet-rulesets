rule sig_20160517_d39c2e0920295cfda723db84f172ff8b {
  meta:
    description = "datamaliciousorder - file 20160517_d39c2e0920295cfda723db84f172ff8b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90079264c689a81ca1b2bf01fee8b0b9aab31b5062aa9c28aca119ba430b08e5"

  strings:
    $s1 = "var cfreyj='vu24itadjsfmrolxli jqesina3phnesrnpkwifmurksob3xxwcjprevbiay4pm2kxudlpba=exjqr\\'g1fg4tb3grrcvnxksnffewtilkewqfi1nwq" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}