rule TTP_XOR_QUAD_CurrentVersionRun_3f7c {
  strings:
    $key_3f7c = { 6c 13 [2] 48 1d [2] 63 31 [2] 4d 13 [2] 59 08 [2] 56 12 [2] 48 0f [2] 4a 0e [2] 51 08 [2] 4d 0f [2] 51 20 }

  condition:
    any of them
}