rule TTP_XOR_QUAD_CurrentVersionRun_162c {
  strings:
    $key_162c = { 45 43 [2] 61 4d [2] 4a 61 [2] 64 43 [2] 70 58 [2] 7f 42 [2] 61 5f [2] 63 5e [2] 78 58 [2] 64 5f [2] 78 70 }

  condition:
    any of them
}