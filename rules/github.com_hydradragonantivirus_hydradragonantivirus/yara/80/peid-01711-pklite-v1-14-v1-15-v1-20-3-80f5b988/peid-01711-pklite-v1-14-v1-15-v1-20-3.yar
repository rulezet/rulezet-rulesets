rule PEiD_01711_PKLITE_v1_14__v1_15__v1_20__3__ {
  meta:
    description = "[PKLITE v1.14, v1.15, v1.20 (3)]"
    ep_only     = "true"

  strings:
    $a = { B8 ?? ?? BA ?? ?? 05 ?? ?? 3B ?? ?? ?? 72 ?? B4 09 BA ?? 01 CD 21 CD 20 4E 6F }

  condition:
    $a
}