rule TTP_XOR_WriteProcessMemory_cec1 {
  strings:
    $key_cec1 = { 99 b3 [2] ab 91 [2] ad a4 [2] 83 a4 [2] bc b8 }

  condition:
    any of them
}