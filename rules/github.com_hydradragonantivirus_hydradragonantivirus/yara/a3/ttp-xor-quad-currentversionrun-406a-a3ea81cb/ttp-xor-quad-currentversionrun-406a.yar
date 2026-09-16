rule TTP_XOR_QUAD_CurrentVersionRun_406a {
  strings:
    $key_406a = { 13 05 [2] 37 0b [2] 1c 27 [2] 32 05 [2] 26 1e [2] 29 04 [2] 37 19 [2] 35 18 [2] 2e 1e [2] 32 19 [2] 2e 36 }

  condition:
    any of them
}