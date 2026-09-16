rule TTP_XOR_QUAD_CurrentVersionRun_1412 {
  strings:
    $key_1412 = { 47 7d [2] 63 73 [2] 48 5f [2] 66 7d [2] 72 66 [2] 7d 7c [2] 63 61 [2] 61 60 [2] 7a 66 [2] 66 61 [2] 7a 4e }

  condition:
    any of them
}