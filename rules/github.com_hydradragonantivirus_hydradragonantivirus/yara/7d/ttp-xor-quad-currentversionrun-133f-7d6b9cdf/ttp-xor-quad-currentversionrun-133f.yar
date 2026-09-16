rule TTP_XOR_QUAD_CurrentVersionRun_133f {
  strings:
    $key_133f = { 40 50 [2] 64 5e [2] 4f 72 [2] 61 50 [2] 75 4b [2] 7a 51 [2] 64 4c [2] 66 4d [2] 7d 4b [2] 61 4c [2] 7d 63 }

  condition:
    any of them
}