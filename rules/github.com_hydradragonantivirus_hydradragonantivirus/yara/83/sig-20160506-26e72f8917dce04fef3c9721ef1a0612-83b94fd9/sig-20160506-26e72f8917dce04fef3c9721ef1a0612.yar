rule sig_20160506_26e72f8917dce04fef3c9721ef1a0612 {
  meta:
    description = "datamaliciousorder - file 20160506_26e72f8917dce04fef3c9721ef1a0612.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "365dfd42734c6d7cdfba161243857d123d41ccabe576ea4626ffcf29b0931033"

  strings:
    $s1 = "while (xQ92Eek4['' + ('mAeA', 'Nl', 'rMN'.a()) + ('jD', 'eCN'.a()) + ('GVbt0', '8fY', 'c9oL', 'rh', 'ap'.a()) + 'd' + 'y' + ('Iz" ascii
    $s2 = "while (xQ92Eek4['' + ('mAeA', 'Nl', 'rMN'.a()) + ('jD', 'eCN'.a()) + ('GVbt0', '8fY', 'c9oL', 'rh', 'ap'.a()) + 'd' + 'y' + ('Iz" ascii
    $s3 = "{return this.split('').reverse().pop();}" fullword ascii
    $s4 = "function String.prototype.a()" fullword ascii
    $s5 = "}catch(ZIvOxwCvzw) {};" fullword ascii
    $s6 = "}catch(WVD53mW){};" fullword ascii

  condition:
    uint16(0) == 0x6c50 and
    all of them
}