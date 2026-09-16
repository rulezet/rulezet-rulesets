rule sig_20160301_5eb366dbc91fba4f97a155e5222ed96e {
  meta:
    description = "datamaliciousorder - file 20160301_5eb366dbc91fba4f97a155e5222ed96e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f263370aa4cda247ad6750731bfc4f3985e0df30834636fcade82ce97650c84"

  strings:
    $s1 = "while (resolutionMethod[(\"in\" + \"\\u0064\" + \"us\\u0074r\" + \"i\\u0061l\\u0069\" + \"\\u007a\\u0061\" + \"\\u0074\\u0069\" " ascii
    $s2 = "\\u0062l\\u0061\\u006e\" + \"\\u006b\", \"i\\u006e\" + \"te\\u0072n\\u0061\\u0074\" + \"\\u0069\" + \"o\\u006ea\\u006c\", functi" ascii
    $s3 = "vulgarAcrobat = associationTitle[(\"\\u006di\\u006e\\u0075\\u0073\", \"s\\u0069m\\u0075\" + \"l\\u0061\" + \"\\u0074e\", \"b\\u0" ascii
    $s4 = "while (resolutionMethod[(\"in\" + \"\\u0064\" + \"us\\u0074r\" + \"i\\u0061l\\u0069\" + \"\\u007a\\u0061\" + \"\\u0074\\u0069\" " ascii
    $s5 = "associationTitle = (((([+[]])) ^ (0 | 1)), this);" fullword ascii
    $s6 = "} catch (portionClip) {};" fullword ascii

  condition:
    uint16(0) == 0x7361 and
    all of them
}