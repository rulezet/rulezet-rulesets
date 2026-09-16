rule TTP_XOR_QUAD_CurrentVersionRun_beb2 {
  strings:
    $key_beb2 = { ed dd [2] c9 d3 [2] e2 ff [2] cc dd [2] d8 c6 [2] d7 dc [2] c9 c1 [2] cb c0 [2] d0 c6 [2] cc c1 [2] d0 ee }

  condition:
    any of them
}