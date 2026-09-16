rule sig_20160526_168583e3a68d17f0f0eddf9461472faa {
  meta:
    description = "datamaliciousorder - file 20160526_168583e3a68d17f0f0eddf9461472faa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe56e9e6f060850963e120836e24bca8225626fa473b1a360d1f025c526c1cd2"

  strings:
    $s1  = "round((Math.pow(Math.sin(811), 2) + Math.pow(Math.cos(811), 2) - 1))-320)) qFBTgRyr += kX(mfOgIsoWqqJiMvgFwOWje);else if (yOKCco" ascii
    $s2  = "((Math.pow(Math.sin(523), 2) + Math.pow(Math.cos(523), 2) - 1))-720) & 0xff;wrhqt = ZGchHrvn & 0xff;if (ezyOUQXh == (384 + Math." ascii
    $s3  = "function HaiRDF(XiVauLhgkHUgs) {var JpUHpfxXTXORmnvBEPfSHcZF = mHuugNPFRyubdyQsf.join(DclHlgTBzWiLETEWGfOx[0]);var mfOgIsoWqqJiM" ascii
    $s4  = "BTudvXXZYmfKZkwu<< (724 + Math.round((Math.pow(Math.sin(564), 2) + Math.pow(Math.cos(564), 2) - 1))-712) | ezyOUQXh<< (45 + Math" ascii
    $s5  = "function qXqBPBTqWIgTmJnrx(oqDZCdfATJMIkXfnwA,KwhJFPFeI){return oqDZCdfATJMIkXfnwA.charAt(KwhJFPFeI);}" fullword ascii
    $s6  = "function FwudsqwRs(XBdfdGB,gHZZukP,UyfqrAWwAI){return String.fromCharCode(XBdfdGB,gHZZukP,UyfqrAWwAI);}" fullword ascii
    $s7  = "g(mfOgIsoWqqJiMvgFwOWje, DuKgYfgznwSi);else qFBTgRyr += FwudsqwRs(mfOgIsoWqqJiMvgFwOWje, DuKgYfgznwSi, wrhqt);} while (MosZDfQiV" ascii
    $s8  = "ibdNNWNTue < XiVauLhgkHUgs.length);return qFBTgRyr;}" fullword ascii
    $s9  = "function kX(omhCKXthIDkpVlvk){return String.fromCharCode(omhCKXthIDkpVlvk);}" fullword ascii
    $s10 = "function HaiRDF(XiVauLhgkHUgs) {var JpUHpfxXTXORmnvBEPfSHcZF = mHuugNPFRyubdyQsf.join(DclHlgTBzWiLETEWGfOx[0]);var mfOgIsoWqqJiM" ascii
    $s11 = "function lrFVJWjOKFXFxcnXYtPZr(gukjMFTu,fffdOZ){return gukjMFTu.indexOf(fffdOZ);}" fullword ascii
    $s12 = "function JwfokUvJYbicMuNnxPVERVUg(QgDbcJuMGuAICayDjmEZEtAn,fAaiNbMmPTWQjk){return String.fromCharCode(QgDbcJuMGuAICayDjmEZEtAn,f" ascii
    $s13 = "function JwfokUvJYbicMuNnxPVERVUg(QgDbcJuMGuAICayDjmEZEtAn,fAaiNbMmPTWQjk){return String.fromCharCode(QgDbcJuMGuAICayDjmEZEtAn,f" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}