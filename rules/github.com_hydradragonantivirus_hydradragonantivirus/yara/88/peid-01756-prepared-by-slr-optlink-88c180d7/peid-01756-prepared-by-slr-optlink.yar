rule PEiD_01756_Prepared_by_SLR__OPTLINK__ {
  meta:
    description = "[Prepared by SLR (OPTLINK)]"
    ep_only     = "true"

  strings:
    $a = { 87 C0 55 56 57 52 51 53 50 9C FC 8C DA 83 ?? ?? 16 07 0E 1F }

  condition:
    $a
}