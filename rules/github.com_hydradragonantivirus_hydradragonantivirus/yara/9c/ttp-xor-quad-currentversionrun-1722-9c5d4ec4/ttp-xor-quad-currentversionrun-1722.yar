rule TTP_XOR_QUAD_CurrentVersionRun_1722 {
  strings:
    $key_1722 = { 44 4d [2] 60 43 [2] 4b 6f [2] 65 4d [2] 71 56 [2] 7e 4c [2] 60 51 [2] 62 50 [2] 79 56 [2] 65 51 [2] 79 7e }

  condition:
    any of them
}