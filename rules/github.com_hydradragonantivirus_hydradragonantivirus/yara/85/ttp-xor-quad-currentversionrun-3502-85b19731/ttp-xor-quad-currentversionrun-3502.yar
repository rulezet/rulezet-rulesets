rule TTP_XOR_QUAD_CurrentVersionRun_3502 {
  strings:
    $key_3502 = { 66 6d [2] 42 63 [2] 69 4f [2] 47 6d [2] 53 76 [2] 5c 6c [2] 42 71 [2] 40 70 [2] 5b 76 [2] 47 71 [2] 5b 5e }

  condition:
    any of them
}