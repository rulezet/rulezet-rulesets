rule Virus_Hijack_Gen_Trojan_ShellObject_p8W_aeeNAYk_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.p8W@aeeNAYk_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d230646d76c07255884b410707dffcb8fa4c5f7332bdc1279f05ee233601520"

  strings:
    $s1  = ".?AV?$TemplatedGenerator@VTableLookupOsc_@Tonic_@Tonic@@@Tonic@@" fullword ascii
    $s2  = "C:\\Program Files (x86)\\Microsoft Visual Studio 9.0\\VC\\ATLMFC\\INCLUDE\\afxwin1.inl" fullword wide
    $s3  = "C:\\Program Files (x86)\\Microsoft Visual Studio 9.0\\VC\\ATLMFC\\INCLUDE\\afxwin2.inl" fullword wide
    $s4  = ".?AV?$TemplatedFilter@VLPF24@Tonic@@VLPF24_@Tonic_@2@@Tonic@@" fullword ascii
    $s5  = ".?AV?$TemplatedWetDryEffect@VStereoDelay@Tonic@@VStereoDelay_@Tonic_@2@@Tonic@@" fullword ascii
    $s6  = ".?AV?$TemplatedEffect@VLimiter@Tonic@@VCompressor_@Tonic_@2@@Tonic@@" fullword ascii
    $s7  = ".?AV?$TemplatedBufferFiller@VSynth_@Tonic_@Tonic@@@Tonic@@" fullword ascii
    $s8  = ".?AV?$TemplatedGenerator@VCompressor_@Tonic_@Tonic@@@Tonic@@" fullword ascii
    $s9  = ".?AV?$TemplatedGenerator@VStereoDelay_@Tonic_@Tonic@@@Tonic@@" fullword ascii
    $s10 = ".?AV?$TemplatedGenerator@VAngularWave_@Tonic_@Tonic@@@Tonic@@" fullword ascii
    $s11 = ".?AV?$TemplatedGenerator@VRectWaveBL_@Tonic_@Tonic@@@Tonic@@" fullword ascii
    $s12 = "I@TableLookUpOsc lookup tables must have a (power-of-two + 1) number of samples (example 2049 or 4097). Resizing to nearest powe" ascii
    $s13 = ".?AV?$TemplatedGenerator@VAdder_@Tonic_@Tonic@@@Tonic@@" fullword ascii
    $s14 = ".?AV?$TemplatedGenerator@VFixedValue_@Tonic_@Tonic@@@Tonic@@" fullword ascii
    $s15 = ".?AV?$TemplatedGenerator@VADSR_@Tonic_@Tonic@@@Tonic@@" fullword ascii
    $s16 = ".?AV?$TemplatedGenerator@VMultiplier_@Tonic_@Tonic@@@Tonic@@" fullword ascii
    $s17 = ".?AV?$TemplatedGenerator@VLPF24_@Tonic_@Tonic@@@Tonic@@" fullword ascii
    $s18 = ".?AV?$TemplatedEffect@VLPF24@Tonic@@VLPF24_@Tonic_@2@@Tonic@@" fullword ascii
    $s19 = "I@TableLookUpOsc lookup tables must have a (power-of-two + 1) number of samples (example 2049 or 4097). Resizing to nearest powe" ascii
    $s20 = "Tonic::error: %s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}