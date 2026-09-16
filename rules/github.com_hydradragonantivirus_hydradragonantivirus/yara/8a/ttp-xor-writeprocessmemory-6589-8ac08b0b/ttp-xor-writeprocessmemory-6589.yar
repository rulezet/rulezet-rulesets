rule TTP_XOR_WriteProcessMemory_6589 {
  strings:
    $key_6589 = { 32 fb [2] 00 d9 [2] 06 ec [2] 28 ec [2] 17 f0 }

  condition:
    any of them
}