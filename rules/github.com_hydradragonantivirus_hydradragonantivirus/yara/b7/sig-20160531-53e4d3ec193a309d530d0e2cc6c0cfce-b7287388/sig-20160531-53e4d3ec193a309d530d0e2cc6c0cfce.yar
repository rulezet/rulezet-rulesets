rule sig_20160531_53e4d3ec193a309d530d0e2cc6c0cfce {
  meta:
    description = "datamaliciousorder - file 20160531_53e4d3ec193a309d530d0e2cc6c0cfce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b76da2c0033ba482f798b48593f34e1b706f0e2c4b1c0d7d582d88a77543819"

  strings:
    $s1  = "var pwWgnnKvhi=function(){return WScript.CreateObject(WSEwHedyCMZLxqcrBpWh[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function kaWwLWyHulkLpgxDdYt(JXOmGkrXZhFILKZUxLgMEJw,BMwkGSbjWKI){return JXOmGkrXZhFILKZUxLgMEJw.charAt(BMwkGSbjWKI);}" fullword ascii
    $s3  = "YKfogEDnYphsJ.length);return NkZdZqg;}" fullword ascii
    $s4  = "function ZH(XOSaqcqysTeXZZrQvCRxisS){return String.fromCharCode(XOSaqcqysTeXZZrQvCRxisS);}" fullword ascii
    $s5  = "function RxFDOEv(yaAozYZc,CqqCeKS,FVDkU){MZWccxuI=yaAozYZc.split(FVDkU);ZRgwp = WSEwHedyCMZLxqcrBpWh[0];for(enkFqHJGzdsjLE=0;enk" ascii
    $s6  = "function OCjOqRbHitawMUPHSDicXjSW(QkGpMTNixyzAsGJfqO,UnpDbrympldNlOLI){return QkGpMTNixyzAsGJfqO.indexOf(UnpDbrympldNlOLI);}" fullword ascii
    $s7  = "(rCEPidamDWW,0x1,0x0)}function VUUDluEShs(TXLTF,mLCwtbAhpV,FTSWSx){var zJjFUf=TXLTF.createtextfile(mLCwtbAhpV,true);zJjFUf.Write" ascii
    $s8  = "function ymNNEqZdugT(YKfogEDnYphsJ) {var TzPemTtWuDb = lxeoMllzNKXGRlOvsnPv.join(WSEwHedyCMZLxqcrBpWh[7]);var zZNEvDzPtuVVWGbf, " ascii
    $s9  = " (uzUhzUuVkgrNTEbawwhXY == 64) NkZdZqg += ZH(zZNEvDzPtuVVWGbf);else if (BfuyIn == 64) NkZdZqg += gfNQSy(zZNEvDzPtuVVWGbf, BHGogU" ascii
    $s10 = "function ymNNEqZdugT(YKfogEDnYphsJ) {var TzPemTtWuDb = lxeoMllzNKXGRlOvsnPv.join(WSEwHedyCMZLxqcrBpWh[7]);var zZNEvDzPtuVVWGbf, " ascii
    $s11 = "function SGvXIfgkuCGO(){return pwWgnnKvhi.ExpandEnvironmentStrings(LwbrCup())}" fullword ascii
    $s12 = "function gfNQSy(fUuPLucTwTqfiZMASfsy,ZiObfpCFZlXAhnYw){return String.fromCharCode(fUuPLucTwTqfiZMASfsy,ZiObfpCFZlXAhnYw);}" fullword ascii
    $s13 = "Line(FTSWSx);zJjFUf.Close();}" fullword ascii
    $s14 = "function CyuwBrZCI(qFLlNFTWBhuS,rCEPidamDWW) {var ORmBLrL=[WSEwHedyCMZLxqcrBpWh[15]];qFLlNFTWBhuS[ORmBLrL[0]]" fullword ascii
    $s15 = "function FgDGHNRpvVImVS(KRJhLpHfthIyBzZmldIQI,HgNVLpAgzdQHXnnScQ,GaFFgGjvk){return String.fromCharCode(KRJhLpHfthIyBzZmldIQI,HgN" ascii
    $s16 = "function RxFDOEv(yaAozYZc,CqqCeKS,FVDkU){MZWccxuI=yaAozYZc.split(FVDkU);ZRgwp = WSEwHedyCMZLxqcrBpWh[0];for(enkFqHJGzdsjLE=0;enk" ascii
    $s17 = "function LwbrCup(){return RxFDOEv(WSEwHedyCMZLxqcrBpWh[9],[1,5,7],WSEwHedyCMZLxqcrBpWh[10]);}" fullword ascii
    $s18 = "jrSWdwoBZVSINKy);else NkZdZqg += FgDGHNRpvVImVS(zZNEvDzPtuVVWGbf, BHGogUjrSWdwoBZVSINKy, IOaSbLutSjjadN);} while (cJGibmkZurm < " ascii
    $s19 = "(rCEPidamDWW,0x1,0x0)}function VUUDluEShs(TXLTF,mLCwtbAhpV,FTSWSx){var zJjFUf=TXLTF.createtextfile(mLCwtbAhpV,true);zJjFUf.Write" ascii
    $s20 = "function UlaIqTjESXEK(){return RxFDOEv(WSEwHedyCMZLxqcrBpWh[13],[0,3,6],WSEwHedyCMZLxqcrBpWh[14]);}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}