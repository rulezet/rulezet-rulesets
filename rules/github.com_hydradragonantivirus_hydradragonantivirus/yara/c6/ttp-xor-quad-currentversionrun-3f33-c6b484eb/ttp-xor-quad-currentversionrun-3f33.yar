rule TTP_XOR_QUAD_CurrentVersionRun_3f33 {
  strings:
    $key_3f33 = { 6c 5c [2] 48 52 [2] 63 7e [2] 4d 5c [2] 59 47 [2] 56 5d [2] 48 40 [2] 4a 41 [2] 51 47 [2] 4d 40 [2] 51 6f }

  condition:
    any of them
}