rule TTP_XOR_QUAD_CurrentVersionRun_5712 {
  strings:
    $key_5712 = { 04 7d [2] 20 73 [2] 0b 5f [2] 25 7d [2] 31 66 [2] 3e 7c [2] 20 61 [2] 22 60 [2] 39 66 [2] 25 61 [2] 39 4e }

  condition:
    any of them
}