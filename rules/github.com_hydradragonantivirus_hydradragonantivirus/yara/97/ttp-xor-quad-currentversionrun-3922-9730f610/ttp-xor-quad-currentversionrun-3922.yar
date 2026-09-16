rule TTP_XOR_QUAD_CurrentVersionRun_3922 {
  strings:
    $key_3922 = { 6a 4d [2] 4e 43 [2] 65 6f [2] 4b 4d [2] 5f 56 [2] 50 4c [2] 4e 51 [2] 4c 50 [2] 57 56 [2] 4b 51 [2] 57 7e }

  condition:
    any of them
}