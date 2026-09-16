rule PEiD_03557_Zurenava_DOS_Extender_v0_45__v0_49_ {
  meta:
    description = "[Zurenava DOS Extender v0.45, v0.49]"
    ep_only     = "true"

  strings:
    $a = { BE ?? ?? BF ?? ?? B9 ?? ?? 56 FC F3 A5 5F E9 }

  condition:
    $a
}