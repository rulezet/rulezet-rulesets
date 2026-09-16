rule TTP_XOR_QUAD_CurrentVersionRun_11ee {
  strings:
    $key_11ee = { 42 81 [2] 66 8f [2] 4d a3 [2] 63 81 [2] 77 9a [2] 78 80 [2] 66 9d [2] 64 9c [2] 7f 9a [2] 63 9d [2] 7f b2 }

  condition:
    any of them
}