rule TTP_XOR_QUAD_CurrentVersionRun_6bed {
  strings:
    $key_6bed = { 38 82 [2] 1c 8c [2] 37 a0 [2] 19 82 [2] 0d 99 [2] 02 83 [2] 1c 9e [2] 1e 9f [2] 05 99 [2] 19 9e [2] 05 b1 }

  condition:
    any of them
}