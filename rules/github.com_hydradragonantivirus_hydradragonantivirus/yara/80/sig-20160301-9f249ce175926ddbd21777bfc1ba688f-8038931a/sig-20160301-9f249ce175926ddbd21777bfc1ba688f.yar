rule sig_20160301_9f249ce175926ddbd21777bfc1ba688f {
  meta:
    description = "datamaliciousorder - file 20160301_9f249ce175926ddbd21777bfc1ba688f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24101dbe2abd9e2576181dbd31d4e37d3c536398043cbe99b03774d577825049"

  strings:
    $s1 = "while(vibrationCombine[(\"re\\u0061dy\" + \"\\u0073t\\u0061\\u0074\\u0065\")] < ((([!+[] + !+[]])) * (1 * 2))) {" fullword ascii
    $s2 = "1\\u006c\\u0069\" + \"\\u007a\" + \"at\\u0069o\" + \"n\", function String.prototype.arsenalRegenerate() {" fullword ascii
    $s3 = "positionVeteran[(\"\\u0064o\\u0075\" + \"\\u0062\" + \"le\", \"\\u0064\\u0069\\u0072\" + \"\\u0065\" + \"c\\u0074\" + \"i\\u0076" ascii
    $s4 = "positionVeteran = (((([+!+[]])) & (0 + 1)), this);" fullword ascii
    $s5 = "} catch(provocationMemorandum) {};" fullword ascii

  condition:
    uint16(0) == 0x6f70 and
    all of them
}