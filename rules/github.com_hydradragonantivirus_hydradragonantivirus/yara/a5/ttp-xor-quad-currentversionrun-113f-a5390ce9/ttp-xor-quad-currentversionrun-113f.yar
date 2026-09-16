rule TTP_XOR_QUAD_CurrentVersionRun_113f {
  strings:
    $key_113f = { 42 50 [2] 66 5e [2] 4d 72 [2] 63 50 [2] 77 4b [2] 78 51 [2] 66 4c [2] 64 4d [2] 7f 4b [2] 63 4c [2] 7f 63 }

  condition:
    any of them
}