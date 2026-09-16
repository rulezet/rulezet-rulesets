rule System_Network_Discovery {
  meta:
    mitre = "T1016 System Network Configuration Discovery"

  strings:
    $a  = "checkip.dyndns.org"
    $n  = "/usr/sbin/networksetup"
    $n1 = "listnetworkserviceorder"
    $N  = "/usr/sbin/networksetup" base64
    $N1 = "listnetworkserviceorder" base64

  condition:
    any of them
}