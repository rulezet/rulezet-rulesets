rule sig_20160301_60f712dceadbf6e41e35871bac0da735 {
  meta:
    description = "datamaliciousorder - file 20160301_60f712dceadbf6e41e35871bac0da735.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6b5e9c0b6d94f55b94c8968bb5676f20efabb9fbf69edfab076abe7447b109d"

  strings:
    $s1 = "acrobatPotentiality = blankBall[(\"industry\", \"contribution\", \"convention\", \"ExpandEnvironmentStrings\")]((\"universal\", " ascii
    $s2 = "TEMP%/\")) + (\"chanceAngel\") + (\"produce\", \".scr\");" fullword ascii
    $s3 = "balloonFragment[(\"autonomy\", \"meridian\", \"isolate\", \"WScript\")][(\"reserve\", \"terminology\", function String.prototype" ascii
    $s4 = "balloonFragment[(\"autonomy\", \"meridian\", \"isolate\", \"WScript\")][(\"reserve\", \"terminology\", function String.prototype" ascii
    $s5 = "while (investmentSocial[(\"readystate\")] < ((416 / 8) / ((((([+!+[]])) + \"\" + (([!+[] + !+[] + !+[]]))))))) {" fullword ascii
    $s6 = "balloonFragment = (((5 ^ 160), ((((([!+[] + !+[] + !+[]])) + \"\" + (([+!+[]])))) * ([!+[] + !+[]]) * ([!+[] + !+[]])), 31 * 3, " ascii
    $s7 = "3 + 92)), this);" fullword ascii
    $s8 = "} catch (sabotageDogma) {};" fullword ascii

  condition:
    uint16(0) == 0x6162 and
    all of them
}