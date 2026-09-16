rule Win_Trojan_Agent_33615
{
strings:
	$a0 = { 49fd7f73679f791baf317675a0961c79648759ab6957dea667b62c7dbae2a1c0a59ff773122ff5b1bc5b9eb539364ff83487bc1d90d91ecd5f9c8049e4e9adce3d8e43688ca0eb9ec689ddbdcf5e9b230a8a }


condition:
	$a0
}