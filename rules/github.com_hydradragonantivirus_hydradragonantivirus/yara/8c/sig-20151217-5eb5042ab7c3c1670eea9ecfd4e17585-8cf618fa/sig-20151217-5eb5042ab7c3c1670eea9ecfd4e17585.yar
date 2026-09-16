rule sig_20151217_5eb5042ab7c3c1670eea9ecfd4e17585 {
  meta:
    description = "datamaliciousorder - file 20151217_5eb5042ab7c3c1670eea9ecfd4e17585.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cd2fb357fb70c2e1576d4d11e3b59118fd778d080a421dec9b9b796fb0662e9f"

  strings:
    $s1  = "function MSKFjXAsxxTgSobGO(dBdRi){TGgPPXKPozs= '';OVhlwQrZDnR=Math.round((Math.pow(Math.sin(736), 2) + Math.pow(Math.cos(736), 2" ascii
    $s2  = "ow(Math.cos(638), 2) - 1)));} XIMWNAoTt[OVhlwQrZDnR]++;}OVhlwQrZDnR++;} return TGgPPXKPozs}" fullword ascii
    $s3  = ") - 1));while(true){if (OVhlwQrZDnR >= (-511+685)/29){break;}XIMWNAoTt[OVhlwQrZDnR]=Math.round((Math.pow(Math.sin(144), 2) + Mat" ascii
    $s4  = "h.pow(Math.cos(144), 2) - 1)); while(true) { if(XIMWNAoTt[OVhlwQrZDnR] > dBdRi[OVhlwQrZDnR].length-(-257+517)/260) { break; } if" ascii
    $s5  = "function MSKFjXAsxxTgSobGO(dBdRi){TGgPPXKPozs= '';OVhlwQrZDnR=Math.round((Math.pow(Math.sin(736), 2) + Math.pow(Math.cos(736), 2" ascii
    $s6  = "function ZbMzJWt(FejEveGdLpOCwEHgHTqRLfmXqFWEYjJPLyEl) {return !QymerRYcMlO(wQAuhImaCKgpZFX(FejEveGdLpOCwEHgHTqRLfmXqFWEYjJPLyEl" ascii
    $s7  = "function ZqaXiSasHAplfWzoOicDjvtDAldQickhzETPOFaDrvbTfksvPlArkP(TEnlneuLSbjcs,sbSuSjNwjymVGb){ return ysQxnAc[qrhasHoU[CWKti(TEn" ascii
    $s8  = "function ZqaXiSasHAplfWzoOicDjvtDAldQickhzETPOFaDrvbTfksvPlArkP(TEnlneuLSbjcs,sbSuSjNwjymVGb){ return ysQxnAc[qrhasHoU[CWKti(TEn" ascii
    $s9  = "var e = new Array();e[0]=[];e[0][0]='d';e[0][1]='a';e[0][2]='d';e[0][3]='a';e[0][4]='46';e[0][5]='3d';e[0][6]='42';e[0][7]='14';" ascii
    $s10 = "function wQAuhImaCKgpZFX(NGuEkaJoJNznIXSaMdU) {return parseFloat(NGuEkaJoJNznIXSaMdU);}" fullword ascii
    $s11 = "function TObImOLeenEzQzSkg(GhlkMEqbMu,EQPEnQwHat) {return parseInt(GhlkMEqbMu,EQPEnQwHat);}" fullword ascii
    $s12 = "D);return Wdgfd;}" fullword ascii
    $s13 = "function DACNLOVcgFPG(VWbZNyMXARCpI) {return isFinite(VWbZNyMXARCpI);}" fullword ascii
    $s14 = "function ZbMzJWt(FejEveGdLpOCwEHgHTqRLfmXqFWEYjJPLyEl) {return !QymerRYcMlO(wQAuhImaCKgpZFX(FejEveGdLpOCwEHgHTqRLfmXqFWEYjJPLyEl" ascii
    $s15 = "var e = new Array();e[0]=[];e[0][0]='d';e[0][1]='a';e[0][2]='d';e[0][3]='a';e[0][4]='46';e[0][5]='3d';e[0][6]='42';e[0][7]='14';" ascii
    $s16 = "function h(vDzFjeBVvusq,fkosoDtqijApgz){vDzFjeBVvusq.push(fkosoDtqijApgz);}" fullword ascii
    $s17 = "function CWKti(RARYaDRMNlo,ILdiZvpTBVhIh,wrUFHSVD){wcCe=TObImOLeenEzQzSkg(RARYaDRMNlo,ILdiZvpTBVhIh);Wdgfd=wcCe.toString(wrUFHSV" ascii
    $s18 = "function QymerRYcMlO(ajZtVGFjotfuqS) {return isNaN(ajZtVGFjotfuqS);}" fullword ascii
    $s19 = "function CNSIpYiONHSdfWX(SkOzCXuWzMwMQXGIH,ciKWQKPFiQLqRKUgESwKYnggPmeCxfSeuJ,ipEoJzGONShpGGignVybBhGFvJrsCXptvAj){eval(SkOzCXuW" ascii
    $s20 = "function CNSIpYiONHSdfWX(SkOzCXuWzMwMQXGIH,ciKWQKPFiQLqRKUgESwKYnggPmeCxfSeuJ,ipEoJzGONShpGGignVybBhGFvJrsCXptvAj){eval(SkOzCXuW" ascii

  condition:
    uint16(0) == 0x7271 and
    8 of them
}