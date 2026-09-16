rule sig_20161112_2b7ddc5b2cc67770f1b2643cc462f0b0 {
  meta:
    description = "datamaliciousorder - file 20161112_2b7ddc5b2cc67770f1b2643cc462f0b0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "442a1ef9683c572ab18482ae96444d6f1da9916f7ae8bda20eee76d39244498a"

  strings:
    $s1 = "function String.prototype.T(){var W4gcvjyfuX=(((~-452)<<(128>>0x2))%(~-2));var W4gkQqU=this.split('');if (Number(BtWl39[-1+W4gkQ" ascii
    $s2 = "while(Zt6AGALYL==(((29360128>>10)>>(~-9))%(2048>>0xb))){hGrRXRfMg['' + ('xcyDIy2', 'LHW3C', 'CfB2W_7', 'uFbfzsc', 'oxqN4A'.T()) " ascii
    $s3 = "while(Zt6AGALYL==(((29360128>>10)>>(~-9))%(2048>>0xb))){hGrRXRfMg['' + ('xcyDIy2', 'LHW3C', 'CfB2W_7', 'uFbfzsc', 'oxqN4A'.T()) " ascii
    $s4 = "while(hGrRXRfMg['' + ('sQGNFw', 'H06TkTV', '7vXsW', 'y5Mjp', 'Frbuy', 'r5xNt'.T()) + ('afrFE', '0gKiqx', '6PNzTG', 'iNAlzz', 'qJ" ascii
    $s5 = "function String.prototype.T(){var W4gcvjyfuX=(((~-452)<<(128>>0x2))%(~-2));var W4gkQqU=this.split('');if (Number(BtWl39[-1+W4gkQ" ascii
    $s6 = "w Date();while(v1KinD7cXg8>((~(~292))%(0x800>>0xb))){DrTQB7M=SYtkUeE_PkYf.split(IvzM8fkCkYB);BtWl39.push(DrTQB7M[v1KinD7cXg8%6])" ascii
    $s7 = "while(hGrRXRfMg['' + ('sQGNFw', 'H06TkTV', '7vXsW', 'y5Mjp', 'Frbuy', 'r5xNt'.T()) + ('afrFE', '0gKiqx', '6PNzTG', 'iNAlzz', 'qJ" ascii
    $s8 = "SYtkUeE_PkYf='';var v1KinD7cXg8=(~((-20220438*2-0xa42c54)>>(7<<32)));BtWl39=[];var IvzM8fkCkYB=SYtkUeE_PkYf+' ';SYtkUeE_PkYf+=ne" ascii
    $s9 = "}catch(xlYgorMlr1E){};" fullword ascii

  condition:
    uint16(0) == 0x5953 and
    all of them
}