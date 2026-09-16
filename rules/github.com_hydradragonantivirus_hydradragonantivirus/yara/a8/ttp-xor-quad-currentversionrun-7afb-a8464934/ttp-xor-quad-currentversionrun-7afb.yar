rule TTP_XOR_QUAD_CurrentVersionRun_7afb {
  strings:
    $key_7afb = { 29 94 [2] 0d 9a [2] 26 b6 [2] 08 94 [2] 1c 8f [2] 13 95 [2] 0d 88 [2] 0f 89 [2] 14 8f [2] 08 88 [2] 14 a7 }

  condition:
    any of them
}