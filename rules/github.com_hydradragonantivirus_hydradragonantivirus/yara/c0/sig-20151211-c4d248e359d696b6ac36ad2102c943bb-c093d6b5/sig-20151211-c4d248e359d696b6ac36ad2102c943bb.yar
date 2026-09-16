rule sig_20151211_c4d248e359d696b6ac36ad2102c943bb {
  meta:
    description = "datamaliciousorder - file 20151211_c4d248e359d696b6ac36ad2102c943bb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5f9af22d1d88dc2891d44e4e0e86aea9acecf51ece31cddfbb3cfadfa469cfb"

  strings:
    $s1  = "function DSArIaI(lwBMUEisLYRGkmbySCKUJzjVmJAsOLGHgNom) {return !isNaN(parseFloat(lwBMUEisLYRGkmbySCKUJzjVmJAsOLGHgNom)) && isFin" ascii
    $s2  = "function DSArIaI(lwBMUEisLYRGkmbySCKUJzjVmJAsOLGHgNom) {return !isNaN(parseFloat(lwBMUEisLYRGkmbySCKUJzjVmJAsOLGHgNom)) && isFin" ascii
    $s3  = "function PzbYkVLYgDoCNGCVF(xvJdD){xSJyHqQcQyT= '';kiFqQyTAOpK=(-724+724)/405; while(true){if(kiFqQyTAOpK >= (965+561)/763)break;" ascii
    $s4  = "wnQrPECje[kiFqQyTAOpK]=(-342+342)/612; while(true) { if(wnQrPECje[kiFqQyTAOpK] > xvJdD[kiFqQyTAOpK].length-(641+102)/743) { brea" ascii
    $s5  = "}kiFqQyTAOpK++;} return xSJyHqQcQyT}" fullword ascii
    $s6  = "function LjNmapHNQWI(DsJYpAJu,Hcykkr){return DsJYpAJu.split(Hcykkr)}" fullword ascii
    $s7  = "function jbljp(YclqGhQQCMN,GcFJELyURrxeP,Gvevfwos){YQVQ=parseInt(YclqGhQQCMN,GcFJELyURrxeP);rrqpj=YQVQ.toString(Gvevfwos);return" ascii
    $s8  = " rrqpj;}function DQKCfWJimvsfOIh(PwJUBAcrkWJkmZCZY){eval(PwJUBAcrkWJkmZCZY)}" fullword ascii
    $s9  = "var d=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"41\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s10 = "function evFhPiUgEPdpJUhlCSUsTDIRudgOWdbcMEaQPOsrovWRSHLtSSfzrY(tGLZzIxbEuIEe,qQfffYgAMqEFVY){ return PvAGS[jbljp(tGLZzIxbEuIEe[" ascii
    $s11 = "var d=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"41\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s12 = "function PzbYkVLYgDoCNGCVF(xvJdD){xSJyHqQcQyT= '';kiFqQyTAOpK=(-724+724)/405; while(true){if(kiFqQyTAOpK >= (965+561)/763)break;" ascii
    $s13 = "function jbljp(YclqGhQQCMN,GcFJELyURrxeP,Gvevfwos){YQVQ=parseInt(YclqGhQQCMN,GcFJELyURrxeP);rrqpj=YQVQ.toString(Gvevfwos);return" ascii
    $s14 = "var p=new Array(\"28\",\"2e\",\"28\",\"29\",\"2c\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s15 = "function evFhPiUgEPdpJUhlCSUsTDIRudgOWdbcMEaQPOsrovWRSHLtSSfzrY(tGLZzIxbEuIEe,qQfffYgAMqEFVY){ return PvAGS[jbljp(tGLZzIxbEuIEe[" ascii
    $s16 = "var p=new Array(\"28\",\"2e\",\"28\",\"29\",\"2c\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}