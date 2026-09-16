rule TTP_XOR_QUAD_CurrentVersionRun_b9b4 {
  strings:
    $key_b9b4 = { ea db [2] ce d5 [2] e5 f9 [2] cb db [2] df c0 [2] d0 da [2] ce c7 [2] cc c6 [2] d7 c0 [2] cb c7 [2] d7 e8 }

  condition:
    any of them
}