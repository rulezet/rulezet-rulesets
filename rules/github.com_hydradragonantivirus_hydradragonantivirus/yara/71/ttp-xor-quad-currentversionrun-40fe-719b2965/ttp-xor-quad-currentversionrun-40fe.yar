rule TTP_XOR_QUAD_CurrentVersionRun_40fe {
  strings:
    $key_40fe = { 13 91 [2] 37 9f [2] 1c b3 [2] 32 91 [2] 26 8a [2] 29 90 [2] 37 8d [2] 35 8c [2] 2e 8a [2] 32 8d [2] 2e a2 }

  condition:
    any of them
}