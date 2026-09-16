rule Backdoor_PHP_WPVCD_DivCodeName {
  meta:
    description = "Backdoor script associated with WP-VCD"

  strings:
    $re = /\$div_code_name\s*\=\s*['"]wp_vcd['"];/ nocase

  condition:
    $re
}