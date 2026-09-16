rule TTP_XOR_QUAD_CurrentVersionRun_2942 {
  strings:
    $key_2942 = { 7a 2d [2] 5e 23 [2] 75 0f [2] 5b 2d [2] 4f 36 [2] 40 2c [2] 5e 31 [2] 5c 30 [2] 47 36 [2] 5b 31 [2] 47 1e }

  condition:
    any of them
}