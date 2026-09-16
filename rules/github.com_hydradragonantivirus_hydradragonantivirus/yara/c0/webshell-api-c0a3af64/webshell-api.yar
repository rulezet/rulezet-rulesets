rule webshell_api {
  meta:
    description = "PHP - file webshell_api.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-10-11"
    hash1       = "c4c73576eb6bff8fd1c224adfaa94acdc02e1a36bfdcc486b81bb4fb8687c973"

  strings:
    $s1  = "$DZcvSEa = \"7b1Jd+JK0zX6g57BJwlTz2FwBwZLAmEJoybVzNRQCJQClcGm+fV3R0q0Buw677vWdwd34HUOhZrMyIgde0c29Eq2S8vOLmgZPNU7u0znH9Fuuhm6q2G" ascii
    $s2  = "f/5f\"; $QnER = ''; for ($i = 0; $i < 6; $i++) { $nZz7Ki3 = $L4b6[$i]; $QnER .= $p4VirK[$nZz7Ki3]; }" fullword ascii
    $s3  = "NPGZBO5e0NjUOmIzu/9OcIY+kwZ9wSfxHEPUGsVzqJ+iDYhHGePbp7UZjIsxBzbRNYjNdlLf14p9W4oRK9b8eZP2p//F9/953N/m3bX2oWecfJTR+45tEj5D73vd37H1" ascii
    $s4  = "0/ZtbtG3d5P7ubxocGJKbTW0ztiVLeqXmONC3+7elwXIvbMv98mwz+7RfSnaC3y/vg+62do/ui8pNXD4L/cV4eyEfdd/Rh/53Y+qyQEH1Y7LtNUiRR4BN3l69D7S5Anx" ascii
    $s5  = "Q2/ejJ86v5/p/5+Px9Asx1viT2fx8hFp0C/Sv3zegS9RPemlC/7KbuDhEQ9M5Ki/85+6/nHAO6F/MZ4Uj7fyx8X3/xJf7vCJUz4R+Vo3AsrX8F9cb9H7/sp+6bf8p+HX" ascii
    $s6  = "ka9E7QI5JiWdP0cuhL0jbut8R1gPm7Qd2L+Ox8Hy8h2bn9zza8StV4d1f9tqx/Ou61s6cZ26rifyTslaAw3cvwW/VLgSeafvL9qhf33/6XvDoPwtcsF8+ctVWZcVzA2k" ascii
    $s7  = "xuH727WMs/lNjXQT2w8luye4QfnPQqz7U7WxQ/2e3ZqzXX42cw2iFnRn/mB/R+t/0eFn9ZDrGv2X+5ucIeYE6roIe0qRX2k92YBvP4gXnj3n4INUX/lunX/zzHqdf0Jr" ascii
    $s8  = "Dz5TtnnYgk/3DLSddPx4inH03N0Vni3Eu8X4DHp5E2fwXZ36pf2OFdY+/H8GLZHd9PP0CiOtHPl1BowD/nDwUvJvlcbov+l+uTX3GKtSKxKffwgOXWpS0jJo7GicfwW9" ascii
    $s9  = "bnseldn+/vzAIXZs8E4TPBZjt3jAl6/aFQbd6gtPmT6+/uSPYs3CwlPH7UzRBmNvHftq1Q7n1jAqrTVbZDNTWm5ClspJsVbHQfcta3V/+Tx3otLuJ307ZnO+x/fbVLdf" ascii
    $s10 = "qfujLZy5FSUFV83eura3XnWTYts9tA/9fz/r/3vI8Dxp7T1qr8fGW5ezAOPyKeyL93llxGyXe7DXPiltN9JtE89/91+0nqd527p/2oevWa1IqvQR0zzTazPW4kXmLbdm" ascii
    $s11 = "Tn81L6+fSdiVSrDnDH7VC8vB+b/L2Q79yuGziOFiasxCqm8QL6ljV6X/Zx+hL4vvCYORuxbftfPcbkCcKtMpjoQ/NRh6yOvSf5DLJU/wwft++j3u1X9/zfEeYynwzZbT" ascii
    $s12 = "1xLl0GCRAi5E41E9rjUc378XeKmb20y3Bd4j3gpwR+IyiP+ba7+u4+Pq+fmQ7mcLTvlpE/K8lyp1/JMWD0uhxc/t9bV/Z1rqzH8iswip1rxIZCOMdfADdUD8op2Jtavb" ascii
    $s13 = "s2IX9+2ZycV+04Mebfb6C7wKGnx6cpmtfXuW4bftq/pxyyC98/T3+/OyUVyfLf5qs1Cis08y5bCfXKP9kg/4yQ/PGoCeZFRPVLZ/xP5e31i7dNbinmP8hb7REow4nX0P" ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 90KB and
      (8 of them)
    ) or (all of them)
}