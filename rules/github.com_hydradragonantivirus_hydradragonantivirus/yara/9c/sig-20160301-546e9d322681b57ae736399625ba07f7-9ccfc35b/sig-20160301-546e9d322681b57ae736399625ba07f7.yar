rule sig_20160301_546e9d322681b57ae736399625ba07f7 {
  meta:
    description = "datamaliciousorder - file 20160301_546e9d322681b57ae736399625ba07f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42fa1f63dbb3c1eec538558ec5d1f260b6c3f4e174ed75d769b68ea26f932fa1"

  strings:
    $s1 = "commandNose = (((1 + 9) - (3 * 3)), this);" fullword ascii
    $s2 = "hierarchyAmmunition = commandNose[(\"d\" + \"\\u0065f\\u0065\\u0063\\u0074\", \"bis\" + \"exua\\u006c\", \"\\u0061rct\" + \"\\u0" ascii
    $s3 = "hierarchyAmmunition = commandNose[(\"d\" + \"\\u0065f\\u0065\\u0063\\u0074\", \"bis\" + \"exua\\u006c\", \"\\u0061rct\" + \"\\u0" ascii
    $s4 = "while (provocationCitation[(\"\\u0061\\u0062s\\u0075rd\", \"n\\u006f\\u0072\\u006d\", \"res\" + \"\\u0065rv\\u006f\\u0069\" + \"" ascii
    $s5 = "while (provocationCitation[(\"\\u0061\\u0062s\\u0075rd\", \"n\\u006f\\u0072\\u006d\", \"res\" + \"\\u0065rv\\u006f\\u0069\" + \"" ascii
    $s6 = "} catch (transformArticle) {};" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    all of them
}