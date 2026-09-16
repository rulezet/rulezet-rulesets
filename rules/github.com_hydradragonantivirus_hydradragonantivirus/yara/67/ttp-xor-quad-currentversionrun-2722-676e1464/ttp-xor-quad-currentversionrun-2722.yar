rule TTP_XOR_QUAD_CurrentVersionRun_2722 {
  strings:
    $key_2722 = { 74 4d [2] 50 43 [2] 7b 6f [2] 55 4d [2] 41 56 [2] 4e 4c [2] 50 51 [2] 52 50 [2] 49 56 [2] 55 51 [2] 49 7e }

  condition:
    any of them
}