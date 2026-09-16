rule DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_PE_Resourcetuner: FILE {
  meta:
    description = "Detects executables with modified PE resources using the unpaid version of Resource Tuner"
    author      = "ditekSHen"
    id          = "2ada52b4-de9e-5b66-a05e-da894ca79e48"
    date        = "2024-06-08"
    modified    = "2024-06-08"
    reference   = "https://github.com/ditekshen/detection"
    source_url  = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_suspicious.yar#L793-L801"
    license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
    logic_hash  = "25959ba2f974ecdcda624b4b34cd8dac0336af0dd7c88d2e3b17ec94d58b87b8"
    score       = 40
    quality     = 45
    tags        = "FILE"
    importance  = 20

  strings:
    $s1 = "Modified by an unpaid evaluation copy of Resource Tuner 2 (www.heaventools.com)" fullword wide

  condition:
    uint16(0) == 0x5a4d and all of them
}