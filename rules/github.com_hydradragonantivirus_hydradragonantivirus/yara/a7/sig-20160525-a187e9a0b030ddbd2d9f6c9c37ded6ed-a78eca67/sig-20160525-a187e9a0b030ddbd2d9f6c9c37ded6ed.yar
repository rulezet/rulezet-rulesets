rule sig_20160525_a187e9a0b030ddbd2d9f6c9c37ded6ed {
  meta:
    description = "datamaliciousorder - file 20160525_a187e9a0b030ddbd2d9f6c9c37ded6ed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bfa5527de404bc9a1246f5a8f9eab13f4e2e88c3294aa20d31b357461936e53b"

  strings:
    $s1  = "function xIUqQIoY(dTqSDCvTAjHbE) {var chnQPYjrsBV = gpuQcNzNM.join(dfMkCFQyRKMAbUozwyP[0]);var mAVcIUZOVuTXnyxBtyopWY, jfFxyjZjK" ascii
    $s2  = "BtyopWY);else if (ayrttdJkgShHijhFVdcTKU == (603 + Math.round((Math.pow(Math.sin(686), 2) + Math.pow(Math.cos(686), 2) - 1))-539" ascii
    $s3  = " | ayrttdJkgShHijhFVdcTKU;mAVcIUZOVuTXnyxBtyopWY = uroJjFpQSnbeLQLUKznHBe>> (124 + Math.round((Math.pow(Math.sin(433), 2) + Math" ascii
    $s4  = "function YjcDfUwS(ufOVTBGXMnjZGB,IBawHEftQrVrveNy){return ufOVTBGXMnjZGB.charAt(IBawHEftQrVrveNy);}" fullword ascii
    $s5  = "function XSOqznhlrgXIsXZOlbNvEXzl(uZHUnQTCLwGy,YHQIw){return uZHUnQTCLwGy.indexOf(YHQIw);}" fullword ascii
    $s6  = "function wxtEpiEdpqMfWHxFpd(kauRHXHfxzKmGzckPponUTn,foAXxJkJoV,uCmnsSRDOAJOtthpCPn){return String.fromCharCode(kauRHXHfxzKmGzckP" ascii
    $s7  = "function xIUqQIoY(dTqSDCvTAjHbE) {var chnQPYjrsBV = gpuQcNzNM.join(dfMkCFQyRKMAbUozwyP[0]);var mAVcIUZOVuTXnyxBtyopWY, jfFxyjZjK" ascii
    $s8  = ")) BgIPCHxkxAholjcPBEMTIB += obMynJ(mAVcIUZOVuTXnyxBtyopWY, jfFxyjZjKZSIelFBRlEP);else BgIPCHxkxAholjcPBEMTIB += wxtEpiEdpqMfWHx" ascii
    $s9  = "function obMynJ(wKXELflNKHQEjcNL,yuQdHLdGJCpzImGySyUb){return String.fromCharCode(wKXELflNKHQEjcNL,yuQdHLdGJCpzImGySyUb);}" fullword ascii
    $s10 = "Fpd(mAVcIUZOVuTXnyxBtyopWY, jfFxyjZjKZSIelFBRlEP, hMwnCwcslFZFdDPCZ);} while (jmnraIKuj < dTqSDCvTAjHbE.length);return BgIPCHxkx" ascii
    $s11 = "function wxtEpiEdpqMfWHxFpd(kauRHXHfxzKmGzckPponUTn,foAXxJkJoV,uCmnsSRDOAJOtthpCPn){return String.fromCharCode(kauRHXHfxzKmGzckP" ascii
    $s12 = "function Oc(PWmHGFwPFdeRkmRCiACQwSdT){return String.fromCharCode(PWmHGFwPFdeRkmRCiACQwSdT);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}