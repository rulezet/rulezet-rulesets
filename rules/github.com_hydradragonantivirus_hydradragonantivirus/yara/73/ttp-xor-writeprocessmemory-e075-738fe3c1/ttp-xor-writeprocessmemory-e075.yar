rule TTP_XOR_WriteProcessMemory_e075 {
  strings:
    $key_e075 = { b7 07 [2] 85 25 [2] 83 10 [2] ad 10 [2] 92 0c }

  condition:
    any of them
}