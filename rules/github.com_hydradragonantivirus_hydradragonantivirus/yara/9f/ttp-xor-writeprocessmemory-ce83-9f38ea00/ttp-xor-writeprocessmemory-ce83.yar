rule TTP_XOR_WriteProcessMemory_ce83 {
  strings:
    $key_ce83 = { 99 f1 [2] ab d3 [2] ad e6 [2] 83 e6 [2] bc fa }

  condition:
    any of them
}