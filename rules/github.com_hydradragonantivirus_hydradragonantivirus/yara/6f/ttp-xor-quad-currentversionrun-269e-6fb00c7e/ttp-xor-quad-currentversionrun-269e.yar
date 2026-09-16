rule TTP_XOR_QUAD_CurrentVersionRun_269e {
  strings:
    $key_269e = { 75 f1 [2] 51 ff [2] 7a d3 [2] 54 f1 [2] 40 ea [2] 4f f0 [2] 51 ed [2] 53 ec [2] 48 ea [2] 54 ed [2] 48 c2 }

  condition:
    any of them
}