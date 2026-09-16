rule TTP_XOR_QUAD_CurrentVersionRun_59cd {
  strings:
    $key_59cd = { 0a a2 [2] 2e ac [2] 05 80 [2] 2b a2 [2] 3f b9 [2] 30 a3 [2] 2e be [2] 2c bf [2] 37 b9 [2] 2b be [2] 37 91 }

  condition:
    any of them
}